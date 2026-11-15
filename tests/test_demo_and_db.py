"""Tests for demo/real separation, database reliability, workflow persistence and dashboard accuracy.
Each test uses its own temporary database. Run: python -m unittest discover -s tests -v"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config  # noqa: E402
from core import workflow  # noqa: E402
from core.demo_data import DEMO_CASES  # noqa: E402
from database import db  # noqa: E402

REAL = {"url": "https://www.python.org/downloads/",
        "message": "Your account will be blocked. Share OTP immediately at login-bank.example",
        "email": "From: a@b.example\nSubject: hi\n\nPlease verify at http://x-y-z-w.example/login now",
        "qr_payload": "upi://pay?pa=x@bank&pn=Shop&am=100"}


class TempDbCase(unittest.TestCase):
    def setUp(self):
        self._old = config.DB_PATH
        self._dir = tempfile.TemporaryDirectory()
        config.DB_PATH = Path(self._dir.name) / "t.db"
        db.init_db()

    def tearDown(self):
        config.DB_PATH = self._old
        self._dir.cleanup()


class ConnectionLifecycle(TempDbCase):
    def _tracking(self):
        opened, real = [], sqlite3.connect

        def spy(*a, **k):
            c = real(*a, **k)
            opened.append(c)
            return c
        return opened, patch.object(db.sqlite3, "connect", side_effect=spy)

    @staticmethod
    def _is_closed(conn):
        try:
            conn.execute("SELECT 1")
            return False
        except sqlite3.ProgrammingError:
            return True

    def test_every_operation_closes_its_connection(self):
        opened, p = self._tracking()
        with p:
            _, saved = workflow.run_and_store("message", REAL["message"], REAL["message"])
            db.get_investigation(saved["investigation_id"])
            db.list_investigations()
            db.stats()
            db.count_records()
            db.find_demo_record("url", ["x"])
            db.delete_investigation(saved["investigation_id"])
            db.delete_demo_records()
            db.delete_all()
        self.assertGreaterEqual(len(opened), 8)
        self.assertTrue(all(self._is_closed(c) for c in opened))

    def test_connection_closed_and_rolled_back_on_exception(self):
        holder = {}
        with self.assertRaises(RuntimeError):
            with db.connection() as c:
                holder["c"] = c
                c.execute("INSERT INTO investigations VALUES ('PT-X','t','url','e','c',1,'Low Risk','{}','[]','[]','{}',0)")
                raise RuntimeError("boom")
        self.assertTrue(self._is_closed(holder["c"]))
        self.assertIsNone(db.get_investigation("PT-X"))          # insert was rolled back

    def test_commit_on_success_visible_to_a_fresh_connection(self):
        with db.connection() as c:
            c.execute("INSERT INTO investigations VALUES ('PT-OK','2026-01-01T00:00:00+00:00','url','e','c',1,'Low Risk','{}','[]','[]','{\"x\":1}',0)")
        raw = sqlite3.connect(str(config.DB_PATH))               # independent connection = "after restart"
        try:
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM investigations WHERE id='PT-OK'").fetchone()[0], 1)
        finally:
            raw.close()

    def test_failed_save_is_reported_and_closes_connection(self):
        opened, p = self._tracking()
        with p, patch.object(db, "save_investigation", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(workflow.StorageError):
                workflow.run_and_store("url", REAL["url"], REAL["url"])

    def test_parameterised_queries_resist_injection(self):
        workflow.run_and_store("url", REAL["url"], REAL["url"])
        self.assertIsNone(db.get_investigation("x'; DROP TABLE investigations; --"))
        self.assertEqual(db.stats()["total"], 1)

    def test_existing_database_and_records_are_compatible(self):
        """A DB created by the previous schema/version (random IDs, is_demo column) is read without migration."""
        with db.connection() as c:
            c.execute("INSERT INTO investigations VALUES ('PT-20250101-ABC123','2025-01-01T10:00:00+00:00','url','http://old.example',"
                      "'Likely phishing URL',70,'High Risk','{\"urls\":[]}','[]','[\"r\"]','{\"input_type\":\"url\",\"analysis_time\":"
                      "\"2025-01-01T10:00:00+00:00\",\"classification\":\"Likely phishing URL\",\"risk_score\":70,\"risk_level\":"
                      "\"High Risk\",\"findings\":[],\"entities\":{},\"recommendations\":[\"r\"]}',0)")
        db.init_db()                                              # idempotent re-init must not touch data
        rec = db.get_investigation("PT-20250101-ABC123")
        self.assertEqual((rec["risk_score"], rec["is_demo"]), (70, False))


class RealWorkflow(TempDbCase):
    def test_each_input_type_persists_with_unique_ids_and_full_data(self):
        ids = []
        for kind, evidence in (("url", REAL["url"]), ("email", REAL["email"]), ("message", REAL["message"]),
                               ("qr_payload", REAL["qr_payload"])):
            inv_id, saved = workflow.run_and_store(kind, evidence, evidence)
            ids.append(inv_id)
            got = db.get_investigation(inv_id)
            self.assertFalse(got["is_demo"])
            for key in ("findings", "recommendations", "risk_score", "risk_level", "analysis_time", "evidence", "entities", "classification"):
                self.assertIn(key, got)
            self.assertTrue(got["recommendations"] and got["analysis_time"] and got["evidence"])
            self.assertEqual(got["risk_score"], saved["risk_score"])
        self.assertEqual(len(set(ids)), 4)
        self.assertEqual({r["input_type"] for r in db.list_investigations()}, {"url", "email", "message", "qr"})

    def test_qr_image_scan_persists(self):
        from core.demo_data import make_demo_qr_png
        png = make_demo_qr_png("https://example.com/pay")
        if not png:
            self.skipTest("OpenCV QR encoder unavailable")
        inv_id, saved = workflow.run_and_store("qr", png, "QR image upload")
        self.assertEqual(db.get_investigation(inv_id)["input_type"], "qr")

    def test_delete_one_leaves_others(self):
        a, _ = workflow.run_and_store("url", REAL["url"], REAL["url"])
        b, _ = workflow.run_and_store("message", REAL["message"], REAL["message"])
        db.delete_investigation(a)
        self.assertIsNone(db.get_investigation(a))
        self.assertIsNotNone(db.get_investigation(b))
        self.assertEqual(db.stats()["total"], 1)

    def test_invalid_input_raises_not_silently_dropped(self):
        with self.assertRaises(ValueError):
            workflow.run_and_store("message", "a" * 60_000, "x")
        with self.assertRaises(ValueError):
            workflow.run_and_store("bogus", "x", "x")
        self.assertEqual(db.stats()["total"], 0)

    def test_analysis_bug_is_surfaced_as_error(self):
        with patch("core.risk_engine.analyze", side_effect=KeyError("bug")):
            with self.assertRaises(workflow.AnalysisError):
                workflow.run_and_store("url", REAL["url"], REAL["url"])


class DemoSeparation(TempDbCase):
    def test_text_identical_to_demo_is_still_real(self):
        for case in DEMO_CASES:
            inv_id, _ = workflow.run_and_store(case["type"], case["content"], case["content"])  # default is_demo
            self.assertFalse(db.get_investigation(inv_id)["is_demo"], case["id"])
        self.assertEqual(db.count_records(), {"real": len(DEMO_CASES), "demo": 0})

    def test_explicit_demo_load_marks_demo(self):
        added, existing = workflow.load_demo_records()
        self.assertEqual((len(added), len(existing)), (len(DEMO_CASES), 0))
        self.assertTrue(all(db.get_investigation(i)["is_demo"] for i in added))

    def test_repeated_demo_loading_does_not_duplicate(self):
        workflow.load_demo_records()
        added, existing = workflow.load_demo_records()
        workflow.load_demo_records()
        self.assertEqual((added, len(existing)), ([], len(DEMO_CASES)))
        self.assertEqual(db.count_records()["demo"], len(DEMO_CASES))

    def test_legacy_random_id_demo_records_are_recognised(self):
        case = DEMO_CASES[0]
        from core.risk_engine import analyze
        db.save_investigation(analyze(case["type"], case["content"]), case["content"], is_demo=True)   # old-style random ID
        added, existing = workflow.load_demo_records([case])
        self.assertEqual((added, len(existing)), ([], 1))
        self.assertEqual(db.count_records()["demo"], 1)

    def test_demo_loading_never_touches_real_records(self):
        rid, _ = workflow.run_and_store("url", REAL["url"], REAL["url"])
        before = db.get_investigation(rid)
        workflow.load_demo_records()
        workflow.load_demo_records()
        self.assertEqual(db.get_investigation(rid), before)
        self.assertEqual(db.count_records()["real"], 1)

    def test_real_scan_matching_demo_text_coexists_with_demo_record(self):
        case = DEMO_CASES[0]
        workflow.load_demo_records([case])
        rid, _ = workflow.run_and_store(case["type"], case["content"], case["content"])
        self.assertEqual(db.count_records(), {"real": 1, "demo": 1})
        self.assertFalse(db.get_investigation(rid)["is_demo"])

    def test_delete_demo_only(self):
        workflow.run_and_store("url", REAL["url"], REAL["url"])
        workflow.load_demo_records()
        self.assertEqual(db.delete_demo_records(), len(DEMO_CASES))
        self.assertEqual(db.count_records(), {"real": 1, "demo": 0})


class DashboardStats(TempDbCase):
    def setUp(self):
        super().setUp()
        self.real = [workflow.run_and_store(k, REAL[k], REAL[k])[1] for k in ("url", "message", "message")]
        workflow.load_demo_records()

    def test_default_excludes_demo(self):
        s = db.stats()
        self.assertEqual(s["total"], 3)
        self.assertEqual(sum(s["by_type"].values()), 3)
        self.assertEqual(sum(s["by_level"].values()), 3)
        self.assertEqual(len(s["scores"]), 3)
        self.assertEqual(sum(n for _, n in s["per_day"]), 3)

    def test_explicit_inclusion_adds_demo(self):
        s = db.stats(include_demo=True)
        self.assertEqual(s["total"], 3 + len(DEMO_CASES))
        self.assertEqual(sum(n for _, n in s["per_day"]), s["total"])
        self.assertEqual(sum(s["by_level"].values()), s["total"])

    def test_metrics_match_independent_calculation(self):
        for inc, recs in ((False, self.real), (True, self.real + db.get_many([r["id"] for r in db.list_investigations() if r["is_demo"]]))):
            s = db.stats(include_demo=inc)
            self.assertEqual(s["threats"], sum(r["risk_score"] >= config.THREAT_THRESHOLD for r in recs))
            self.assertEqual(s["high_risk"], sum(r["risk_level"] in ("High Risk", "Critical Risk") for r in recs))
            self.assertAlmostEqual(s["avg_score"], round(sum(r["risk_score"] for r in recs) / len(recs), 1), places=1)

    def test_recent_list_respects_filter(self):
        self.assertTrue(all(not r["is_demo"] for r in db.list_investigations(include_demo=False)))
        self.assertEqual(len(db.list_investigations(include_demo=True)), 3 + len(DEMO_CASES))

    def test_empty_database_reports_none_not_fake_numbers(self):
        db.delete_all()
        s = db.stats()
        self.assertEqual((s["total"], s["threats"], s["high_risk"], s["avg_score"]), (0, 0, 0, None))
        self.assertEqual((s["by_level"], s["by_type"], s["per_day"], s["scores"]), ({}, {}, [], []))

    def test_only_demo_records_gives_empty_default_dashboard(self):
        db.delete_all()
        workflow.load_demo_records()
        self.assertEqual(db.stats()["total"], 0)
        self.assertEqual(db.stats(include_demo=True)["total"], len(DEMO_CASES))


class ScannerUiFlow(TempDbCase):
    """Drives views/scanner.py with a stubbed Streamlit (real Streamlit is not required)."""

    def _run_scanner(self, pressed_key, url_text="", with_demo_state=None):
        class SS(dict):
            __getattr__ = dict.get
        st = MagicMock()
        st.session_state = SS(with_demo_state or {})
        st.columns.side_effect = lambda spec, **k: [st] * (spec if isinstance(spec, int) else len(spec))
        st.tabs.side_effect = lambda labels, **k: [st] * len(labels)
        st.selectbox.side_effect = lambda label, options, **k: list(options)[0]
        st.button.side_effect = lambda label, key=None, **k: key == pressed_key
        st.checkbox.return_value = False
        st.text_input.return_value = url_text
        st.text_area.return_value = ""
        st.file_uploader.return_value = None
        mods = {"streamlit": st, "plotly": MagicMock(), "plotly.express": MagicMock(), "plotly.graph_objects": MagicMock()}
        with patch.dict(sys.modules, mods):
            for m in [m for m in sys.modules if m in ("views.scanner", "utils.ui")]:
                del sys.modules[m]
            import views.scanner as scanner
            scanner.render()
            # emulate Streamlit: an on_click callback runs first, then the script reruns once
            callbacks = [c for c in st.button.call_args_list if c.kwargs.get("key") == pressed_key and c.kwargs.get("on_click")]
            for call in callbacks:
                call.kwargs["on_click"](*call.kwargs.get("args", ()))
            if callbacks:
                st.button.side_effect = lambda label, key=None, **k: False   # a rerun does not re-press the button
                scanner.render()
        return st

    def test_scan_button_with_demo_identical_text_stores_real_record(self):
        self._run_scanner("scan_url", url_text=DEMO_CASES[0]["content"])
        self.assertEqual(db.count_records(), {"real": 1, "demo": 0})

    def test_save_as_demo_button_stores_demo_once(self):
        self._run_scanner("demo_save_url_input")
        self._run_scanner("demo_save_url_input")
        self.assertEqual(db.count_records(), {"real": 0, "demo": 1})

    def test_load_into_scanner_button_creates_no_record(self):
        st = self._run_scanner("demo_btn_url_input")
        self.assertEqual(db.count_records(), {"real": 0, "demo": 0})
        self.assertEqual(st.session_state.get("url_input"), DEMO_CASES[0]["content"])

    def test_rejected_input_shows_error_and_stores_nothing(self):
        st = self._run_scanner("scan_url", url_text="")
        self.assertEqual(db.count_records(), {"real": 0, "demo": 0})
        st.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
