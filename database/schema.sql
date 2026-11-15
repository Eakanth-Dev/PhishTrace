CREATE TABLE IF NOT EXISTS investigations (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,          -- ISO-8601 UTC analysis time
    input_type      TEXT NOT NULL,          -- url | email | message | qr
    evidence        TEXT NOT NULL,          -- submitted evidence (sensitive values masked)
    classification  TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    risk_level      TEXT NOT NULL,
    indicators      TEXT NOT NULL,          -- JSON: extracted entities
    findings        TEXT NOT NULL,          -- JSON list
    recommendations TEXT NOT NULL,          -- JSON list
    result_json     TEXT NOT NULL,          -- full result for re-opening
    is_demo         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_inv_created ON investigations(created_at);
CREATE INDEX IF NOT EXISTS idx_inv_level ON investigations(risk_level);
