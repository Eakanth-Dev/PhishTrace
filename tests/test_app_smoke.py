"""Boots the real Streamlit app headlessly. Skipped automatically when Streamlit is not installed.
Run after `pip install -r requirements.txt`:  python -m unittest tests.test_app_smoke -v"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PHISHTRACE_DB"] = os.path.join(tempfile.mkdtemp(), "smoke.db")
try:
    from streamlit.testing.v1 import AppTest
except Exception:  # pragma: no cover
    AppTest = None


@unittest.skipIf(AppTest is None, "streamlit not installed")
class AppBoot(unittest.TestCase):
    def test_every_page_renders(self):
        at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
        self.assertFalse(at.exception, at.exception)
        for label in at.sidebar.radio[0].options:
            at.sidebar.radio[0].set_value(label).run()
            self.assertFalse(at.exception, f"{label}: {at.exception}")


if __name__ == "__main__":
    unittest.main()
