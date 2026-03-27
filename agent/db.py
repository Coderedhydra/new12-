import sqlite3
from pathlib import Path

from .models import Finding


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_type TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    cwe TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    verification TEXT NOT NULL,
    verification_details TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    request_headers TEXT NOT NULL,
    request_body TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_headers TEXT NOT NULL,
    response_body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(vuln_type, endpoint, title)
);

CREATE TABLE IF NOT EXISTS crawl_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_bytes INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


class FindingsDB:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)
        self._migrate_findings_table()
        self.conn.commit()

    def _migrate_findings_table(self) -> None:
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "verification" not in cols:
            self.conn.execute("ALTER TABLE findings ADD COLUMN verification TEXT NOT NULL DEFAULT 'LIKELY'")
        if "verification_details" not in cols:
            self.conn.execute(
                "ALTER TABLE findings ADD COLUMN verification_details TEXT NOT NULL DEFAULT 'Captured by plugin evidence.'"
            )

    def log_crawl(self, url: str, status_code: int, response_bytes: int) -> None:
        self.conn.execute(
            "INSERT INTO crawl_log(url, status_code, response_bytes) VALUES(?,?,?)",
            (url, status_code, response_bytes),
        )
        self.conn.commit()

    def save_finding(self, finding: Finding) -> bool:
        try:
            self.conn.execute(
                """
                INSERT INTO findings(
                    vuln_type,title,severity,confidence,endpoint,description,remediation,cwe,cvss_score,
                    verification,verification_details,
                    request_method,request_url,request_headers,request_body,response_status,response_headers,response_body,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    finding.vuln_type,
                    finding.title,
                    finding.severity,
                    finding.confidence,
                    finding.endpoint,
                    finding.description,
                    finding.remediation,
                    finding.cwe,
                    finding.cvss_score,
                    finding.verification,
                    finding.verification_details,
                    finding.evidence.request_method,
                    finding.evidence.request_url,
                    finding.evidence.request_headers,
                    finding.evidence.request_body,
                    finding.evidence.response_status,
                    finding.evidence.response_headers,
                    finding.evidence.response_body,
                    finding.created_at,
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def list_findings(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT id,vuln_type,title,severity,confidence,verification,endpoint,cvss_score,created_at FROM findings ORDER BY id DESC"
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def full_findings(self) -> list[dict]:
        cur = self.conn.execute("SELECT * FROM findings ORDER BY id DESC")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
