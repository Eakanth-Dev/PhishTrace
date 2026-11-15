"""Central configuration. Secrets are read from environment variables, a local
.env file, or Streamlit secrets - never hard-coded, never displayed."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (avoids an extra dependency)."""
    if not path.is_file():
        return
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_dotenv(BASE_DIR / ".env")

APP_NAME = "PhishTrace"
APP_TAGLINE = "AI-Powered Cyber Threat Detection & Digital Investigation Platform"
DATA_DIR = Path(os.getenv("PHISHTRACE_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.getenv("PHISHTRACE_DB", DATA_DIR / "phishtrace.db"))
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"
MODEL_DIR = BASE_DIR / "models"

MAX_UPLOAD_BYTES = 5 * 1024 * 1024      # 5 MB per uploaded file
MAX_TEXT_CHARS = 50_000                 # pasted email / message limit
MAX_URL_CHARS = 2048
MAX_EVIDENCE_STORED = 20_000            # characters kept in the database
MAX_URLS_PER_INPUT = 20
MAX_INTEL_LOOKUPS = 5                   # external lookups per scan

RISK_LEVELS = [(25, "Low Risk"), (50, "Medium Risk"), (75, "High Risk"), (101, "Critical Risk")]
THREAT_THRESHOLD = 25                   # score >= this counts as a "threat detected"


def get_secret(name: str, default: str = "") -> str:
    """Environment variable first, then Streamlit secrets. Returns '' if unset."""
    value = os.getenv(name)
    if value:
        return value
    try:  # pragma: no cover - only inside Streamlit
        import streamlit as st
        return str(st.secrets.get(name, default))
    except Exception:
        return default
