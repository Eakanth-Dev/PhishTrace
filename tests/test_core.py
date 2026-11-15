"""Unit tests (stdlib unittest; also runnable with pytest). Run:  python -m unittest discover -s tests -v"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["PHISHTRACE_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from core import evidence_engine, ml_engine, qr_analyzer, recommendation_engine  # noqa: E402
from core.demo_data import DEMO_CASES, make_demo_qr_png  # noqa: E402
from core.email_analyzer import analyze_email  # noqa: E402
from core.message_analyzer import analyze_message  # noqa: E402
from core.risk_engine import analyze, compute_score, level_for  # noqa: E402
from core.findings import make_finding  # noqa: E402
from core.url_analyzer import analyze_url, normalize_url  # noqa: E402
from database import db  # noqa: E402
from utils.helpers import extract_urls, mask_sensitive  # noqa: E402
from utils.pdf_generator import generate_report  # noqa: E402


def names(r):
    return [f["indicator"] for f in r["findings"]]


class UrlTests(unittest.TestCase):
    def test_phishing_like_url(self):
        r = analyze_url("http://secure-sbi-kyc-update.example/login?verify=account")
        n = " ".join(names(r))
        self.assertIn("No HTTPS", n)
        self.assertIn("Brand impersonation", n)

    def test_legit_url_has_no_warnings(self):
        r = analyze_url("https://www.python.org/downloads/")
        self.assertTrue(all(f["severity"] == "info" for f in r["findings"]))

    def test_ip_host_and_obfuscation(self):
        self.assertIn("IP address used as host", names(analyze_url("http://203.0.113.9/x")))
        self.assertIn("Obfuscated IP address", names(analyze_url("http://3232235777/x")))

    def test_typosquat_and_punycode(self):
        self.assertTrue(any("typosquatting" in n for n in names(analyze_url("https://paypa1.com/"))))
        self.assertIn("Punycode / IDN host", names(analyze_url("https://xn--pypal-4ve.com/")))

    def test_dangerous_scheme_and_malformed(self):
        self.assertEqual(analyze_url("javascript:alert(1)")["findings"][0]["severity"], "critical")
        self.assertFalse(analyze_url("")["valid"])
        self.assertIsInstance(analyze_url("http://[::1")["findings"], list)  # must not raise

    def test_defanged_input_and_no_scheme(self):
        self.assertEqual(normalize_url("hxxps://evil[.]example/x")[0], "https://evil.example/x")
        self.assertTrue(normalize_url("example.com/a")[0].startswith("http://"))

    def test_embedded_redirect_and_at(self):
        r = analyze_url("https://good.com@evil.example/?next=http://other.example")
        self.assertIn("Credentials-style '@' in URL", names(r))
        self.assertIn("Embedded redirect target", names(r))

    def test_extract_urls_bare_domain(self):
        self.assertIn("secure-kyc-example.com", extract_urls("verify at secure-kyc-example.com now, mail a@b.com"))


class EmailTests(unittest.TestCase):
    def setUp(self):
        self.demo = [d for d in DEMO_CASES if d["id"] == "kyc_email"][0]["content"]

    def test_extraction(self):
        r = analyze_email(self.demo)
        m = r["meta"]
        self.assertIn("alerts@hdfc-secure-kyc.example", m["from"])
        self.assertIn("support.desk@mailbox-helper.example", m["reply_to"])
        self.assertIn("KYC", m["subject"])
        self.assertEqual(m["auth"]["spf"], "fail")
        self.assertTrue(any("hdfc-secure-kyc.example" in u for u in r["entities"]["urls"]))

    def test_findings(self):
        n = " ".join(names(analyze_email(self.demo)))
        for expected in ("SPF authentication failed", "Reply-To differs", "Link text does not match", "claims 'hdfc'"):
            self.assertIn(expected, n)

    def test_timestamps_are_real(self):
        ev = analyze_email(self.demo)["events"]
        self.assertTrue(ev and ev[0]["time"].startswith("2025-11-10"))

    def test_malformed_and_headerless(self):
        self.assertIsInstance(analyze_email(b"\xff\xfe\x00garbage")["findings"], list)
        r = analyze_email("Your account is blocked. Share OTP now at login-bank.example")
        self.assertFalse(r["meta"]["has_headers"])
        self.assertTrue(r["findings"])

    def test_risky_attachment_name_only(self):
        raw = (b"From: a@b.example\nSubject: invoice\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n"
               b"--XX\nContent-Type: text/plain\n\nsee attached\n--XX\nContent-Type: application/octet-stream\n"
               b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\n\nMZ\n--XX--\n")
        self.assertIn("Risky attachment type", names(analyze_email(raw)))


class MessageTests(unittest.TestCase):
    def test_otp_theft(self):
        r = analyze_message("Please share your OTP with our executive immediately")
        self.assertEqual(r["scam_type"], "OTP / credential theft")

    def test_upi_and_kyc_and_delivery(self):
        self.assertEqual(analyze_message("Approve the collect request and enter your UPI PIN to receive refund")["scam_type"], "UPI payment scam")
        self.assertEqual(analyze_message("Your SBI KYC has expired, account will be blocked")["scam_type"], "Fake KYC / account-block scam")
        self.assertEqual(analyze_message("Your parcel is on hold, pay Rs. 25 redelivery fee")["scam_type"], "Fake delivery notice")

    def test_benign_message(self):
        r = analyze("message", "Hey, are we still meeting for lunch at 1pm tomorrow?")
        self.assertEqual(r["risk_level"], "Low Risk")
        self.assertEqual(r["scam_type"], "")

    def test_url_in_message(self):
        self.assertIn("secure-kyc-example.com", analyze_message("verify at secure-kyc-example.com")["entities"]["urls"][0])


class QrTests(unittest.TestCase):
    def test_upi_payload(self):
        r = analyze("qr_payload", "upi://pay?pa=x@bank&pn=Refund&am=500")
        self.assertEqual(r["input_type"], "qr")
        self.assertGreaterEqual(r["risk_score"], 12)

    def test_invalid_image(self):
        self.assertIsNotNone(qr_analyzer.decode_qr(b"not an image")[1])
        self.assertIsNotNone(qr_analyzer.decode_qr(b"")[1])

    @unittest.skipUnless(make_demo_qr_png("x"), "OpenCV QR encoder unavailable")
    def test_roundtrip_image(self):
        payload = "https://example.com/pay"
        self.assertEqual(qr_analyzer.decode_qr(make_demo_qr_png(payload))[0], [payload])


class RiskTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual([level_for(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)],
                         ["Low Risk", "Low Risk", "Medium Risk", "Medium Risk", "High Risk", "High Risk", "Critical Risk", "Critical Risk"])

    def test_score_monotonic_and_bounded(self):
        fs = [make_finding("a", "x", "high", "t")]
        s1, _ = compute_score(fs)
        s2, _ = compute_score(fs + [make_finding("b", "x", "critical", "t")])
        s3, _ = compute_score([make_finding(str(i), "x", "critical", "t") for i in range(50)])
        self.assertTrue(0 < s1 < s2 <= s3 <= 100)
        self.assertEqual(compute_score([])[0], 0)

    def test_info_findings_add_nothing(self):
        self.assertEqual(compute_score([make_finding("a", "x", "info", "t")])[0], 0)

    def test_no_safe_claim(self):
        r = analyze("url", "https://www.python.org/")
        self.assertEqual(r["risk_level"], "Low Risk")
        self.assertIn("not a guarantee", r["disclaimer"])
        self.assertTrue(any("does not prove safety" in u for u in r["unknowns"]))

    def test_duplicate_indicators_counted_once(self):
        r = analyze("message", "visit http://a-b-c-d.example/login and http://e-f-g-h.example/login now")
        self.assertEqual(len([n for n in names(r) if n == "No HTTPS"]), 1)

    def test_invalid_type_and_oversize(self):
        with self.assertRaises(ValueError):
            analyze("bogus", "x")
        with self.assertRaises(ValueError):
            analyze("message", "a" * 60_000)

    def test_all_demos_run(self):
        for d in DEMO_CASES:
            r = analyze(d["type"], d["content"])
            self.assertIn(r["risk_level"], ("Low Risk", "Medium Risk", "High Risk", "Critical Risk"))
        self.assertEqual(analyze("url", [c for c in DEMO_CASES if c["id"] == "legit_url"][0]["content"])["risk_level"], "Low Risk")
        self.assertGreaterEqual(analyze("url", DEMO_CASES[0]["content"])["risk_score"], 50)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        db.init_db()
        db.delete_all()

    def test_roundtrip_and_stats(self):
        r1 = analyze("message", "Share OTP now, account will be blocked immediately")
        r2 = analyze("url", "https://www.python.org/")
        i1 = db.save_investigation(r1, "Share OTP 123456 now", False)
        db.save_investigation(r2, "https://www.python.org/", True)
        got = db.get_investigation(i1)
        self.assertEqual(got["risk_score"], r1["risk_score"])
        self.assertIn("[MASKED]", got["evidence"])          # OTP value masked before storage
        s = db.stats()                                        # default: demonstration records excluded
        self.assertEqual((s["total"], s["threats"]), (1, 1))
        s_all = db.stats(include_demo=True)
        self.assertEqual((s_all["total"], s_all["threats"]), (2, 1))
        self.assertEqual(len(db.list_investigations()), 2)
        db.delete_investigation(i1)
        self.assertIsNone(db.get_investigation(i1))

    def test_sql_injection_safe(self):
        self.assertIsNone(db.get_investigation("x'; DROP TABLE investigations; --"))
        self.assertEqual(db.stats()["total"], 0)

    def test_mask_sensitive(self):
        self.assertNotIn("4111", mask_sensitive("card 4111 1111 1111 1111"))


class PdfAndEvidenceTests(unittest.TestCase):
    def test_pdf(self):
        r = analyze("message", "Pay \u20b91,500 registration fee <b>now</b> & share OTP")
        r["investigation_id"], r["evidence"] = "PT-TEST-000001", "Pay \u20b91,500 <b>x</b>"
        pdf = generate_report(r)
        self.assertTrue(pdf.startswith(b"%PDF") and len(pdf) > 1500)

    def test_graph_distinguishes_basis(self):
        email = [d for d in DEMO_CASES if d["id"] == "kyc_email"][0]["content"]
        r = analyze("email", email)
        r["investigation_id"] = "PT-X"
        g = evidence_engine.build_graph([r])
        bases = {d["basis"] for _, _, d in g.edges(data=True)}
        self.assertIn("extracted", bases)
        self.assertTrue(len(evidence_engine.graph_table(g)) > 3)

    def test_timeline_uses_real_times(self):
        r = analyze("email", [d for d in DEMO_CASES if d["id"] == "kyc_email"][0]["content"])
        r["investigation_id"] = "PT-X"
        times = [e["time"] for e in evidence_engine.timeline_events([r])]
        self.assertIn(r["analysis_time"], times)
        self.assertTrue(any(t.startswith("2025-11-10") for t in times))


class AssistantAndMlTests(unittest.TestCase):
    def test_assistant_uses_findings(self):
        r = analyze("message", "Share OTP immediately or your account will be blocked")
        r["investigation_id"] = "PT-X"
        ans = recommendation_engine.answer_question("Why was this classified as suspicious?", r)
        self.assertIn("OTP", ans)
        self.assertIn("Recommended", recommendation_engine.answer_question("What should I do?", r))

    def test_ml_unavailable_is_graceful(self):
        self.assertIsNone(ml_engine.predict_proba("http://x.example", Path("/nonexistent.joblib")))

    def test_ml_training_pipeline_mechanics(self):
        """Pipeline test only: uses a tiny SYNTHETIC CSV to verify train/save/load plumbing. It says nothing about accuracy."""
        import csv
        d = tempfile.mkdtemp()
        rows = [(f"https://site{i}.com/page", 0) for i in range(30)] + \
               [(f"http://login-verify-{i}.example/secure/update?account={i}", 1) for i in range(30)]
        with open(os.path.join(d, "t.csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["url", "label"])
            w.writerows(rows)
        m = ml_engine.train_from_csv(os.path.join(d, "t.csv"), out_dir=d)
        self.assertIn("f1", m)
        p = ml_engine.predict_proba("http://login-verify-99.example/secure/update", Path(d) / "url_model.joblib")
        self.assertTrue(p is not None and 0 <= p <= 1)
        with self.assertRaises(ValueError):
            import pandas as pd
            pd.DataFrame({"url": ["a"], "label": [1]}).to_csv(os.path.join(d, "s.csv"), index=False)
            ml_engine.train_from_csv(os.path.join(d, "s.csv"), out_dir=d)


if __name__ == "__main__":
    unittest.main()
