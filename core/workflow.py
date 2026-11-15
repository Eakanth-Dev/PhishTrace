"""Scanner -> analysis -> database workflow, kept free of UI code so it can be tested.

Rules:
* `is_demo` is an explicit argument that defaults to False. It is NEVER inferred from the submitted text,
  so a user who pastes text identical to a demo example still creates a normal (real) record.
* Failures are never swallowed: validation problems raise ValueError, analysis bugs raise AnalysisError,
  database problems raise StorageError. The UI must show them; they are also logged.
"""
import logging

from core import risk_engine
from core.demo_data import DEMO_CASES
from database import db

log = logging.getLogger("phishtrace")


class AnalysisError(RuntimeError):
    pass


class StorageError(RuntimeError):
    pass


def run_and_store(kind: str, content, evidence_text: str, *, is_demo: bool = False, dns: bool = False,
                  intel: bool = False, inv_id: str = None):
    """Analyse and persist. Returns (investigation_id, saved_result_read_back_from_db)."""
    try:
        result = risk_engine.analyze(kind, content, resolve_dns=dns, use_intel=intel)
    except ValueError:
        raise
    except Exception as exc:
        log.exception("analysis failed for input type %s", kind)
        raise AnalysisError(f"Analysis failed ({type(exc).__name__}: {exc})") from exc
    try:
        saved_id = db.save_investigation(result, evidence_text, is_demo=is_demo, inv_id=inv_id)
        saved = db.get_investigation(saved_id)
    except Exception as exc:
        log.exception("could not store investigation")
        raise StorageError(f"The analysis finished but could not be saved ({type(exc).__name__}: {exc})") from exc
    if saved is None:
        raise StorageError("The record was not found after saving.")
    return saved_id, saved


def load_demo_records(cases=None):
    """Explicit demo action. Idempotent: a case that already exists as a demo record is skipped, so repeated
    loading never duplicates. Real records are never read or modified. Returns (added_ids, existing_ids)."""
    added, existing = [], []
    for case in (cases if cases is not None else DEMO_CASES):
        stored_type = "qr" if case["type"] == "qr_payload" else case["type"]
        found = db.get_investigation(db.demo_id(case["id"])) and db.demo_id(case["id"]) or \
            db.find_demo_record(stored_type, [case["content"], "Demo QR payload\n" + case["content"]])
        if found:
            existing.append(found)
            continue
        inv_id, _ = run_and_store(case["type"], case["content"], case["content"], is_demo=True,
                                  inv_id=db.demo_id(case["id"]))
        added.append(inv_id)
    return added, existing
