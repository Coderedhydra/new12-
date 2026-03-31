import json

from ..models import Finding, HttpEvidence
from .base import VulnPlugin


class SecurityHeadersPlugin(VulnPlugin):
    name = "security_headers"

    async def run(self, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        required = [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ]

        base_resp = context.get("base_response")
        if not base_resp:
            return findings

        hdrs = {k.lower(): v for k, v in base_resp.headers.items()}
        missing = [h for h in required if h not in hdrs]
        if not missing:
            return findings

        evidence = HttpEvidence(
            request_method="GET",
            request_url=str(base_resp.request.url),
            request_headers=json.dumps(dict(base_resp.request.headers)),
            request_body="",
            response_status=base_resp.status_code,
            response_headers=json.dumps(dict(base_resp.headers)),
            response_body=base_resp.text[:2000],
        )

        findings.append(
            Finding(
                vuln_type="Security Misconfiguration",
                title="Missing Recommended Security Headers",
                severity="Medium",
                confidence="LIKELY",
                endpoint=str(base_resp.request.url),
                description=f"Missing headers: {', '.join(missing)}",
                remediation="Set security headers globally at the reverse proxy or application layer.",
                cwe="CWE-693",
                cvss_score=5.3,
                verification="CONFIRMED",
                verification_details="Observed directly in HTTP response headers from target.",
                evidence=evidence,
            )
        )
        return findings
