import json

from ..models import Finding, HttpEvidence
from .base import VulnPlugin


class InfoDisclosurePlugin(VulnPlugin):
    name = "info_disclosure"

    async def run(self, context: dict) -> list[Finding]:
        findings: list[Finding] = []

        for page in context.get("pages", []):
            text = page["body"].lower()
            indicators = []
            if "traceback (most recent call last)" in text:
                indicators.append("python traceback")
            if "exception in thread" in text:
                indicators.append("runtime exception")
            if "stack trace" in text:
                indicators.append("stack trace")
            if "debug=true" in text or "debug mode" in text:
                indicators.append("debug mode")
            if not indicators:
                continue

            response = page["response"]
            evidence = HttpEvidence(
                request_method="GET",
                request_url=str(response.request.url),
                request_headers=json.dumps(dict(response.request.headers)),
                request_body="",
                response_status=response.status_code,
                response_headers=json.dumps(dict(response.headers)),
                response_body=response.text[:2000],
            )
            findings.append(
                Finding(
                    vuln_type="Information Disclosure",
                    title="Debug/Error Details Exposed",
                    severity="Medium",
                    confidence="LIKELY",
                    endpoint=str(response.request.url),
                    description=f"Detected indicators: {', '.join(indicators)}",
                    remediation="Disable debug mode and return generic error pages in production.",
                    cwe="CWE-209",
                    cvss_score=5.0,
                    verification="CONFIRMED",
                    verification_details="Debug/error markers were captured in real HTTP response body.",
                    evidence=evidence,
                )
            )

        return findings
