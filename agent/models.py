from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class CrawlTarget:
    url: str
    method: str = "GET"


@dataclass(slots=True)
class HttpEvidence:
    request_method: str
    request_url: str
    request_headers: str
    request_body: str
    response_status: int
    response_headers: str
    response_body: str


@dataclass(slots=True)
class Finding:
    vuln_type: str
    title: str
    severity: str
    confidence: str
    endpoint: str
    description: str
    remediation: str
    cwe: str
    cvss_score: float
    evidence: HttpEvidence
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
