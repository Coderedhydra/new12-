import json
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from ..models import Finding, HttpEvidence
from .base import VulnPlugin


class ReflectionProbePlugin(VulnPlugin):
    name = "reflection_probe"

    async def run(self, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        client: httpx.AsyncClient = context["http_client"]
        limiter = context["limiter"]
        marker = "SAFE_REFLECT_PROBE"

        for url in context.get("crawl", {}).get("urls", []):
            p = urlparse(url)
            qs = parse_qs(p.query)
            if not qs:
                continue
            payload_qs = {k: marker for k in qs.keys()}
            probe_url = urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(payload_qs), p.fragment))

            await limiter.wait()
            try:
                r = await client.get(probe_url)
            except httpx.HTTPError:
                continue

            reflected = [key for key in payload_qs if marker in r.text]
            if not reflected:
                continue

            evidence = HttpEvidence(
                request_method="GET",
                request_url=probe_url,
                request_headers=json.dumps(dict(r.request.headers)),
                request_body="",
                response_status=r.status_code,
                response_headers=json.dumps(dict(r.headers)),
                response_body=r.text[:2000],
            )
            findings.append(
                Finding(
                    vuln_type="Input Reflection",
                    title="Unsanitized Input Reflection Detected",
                    severity="Low",
                    confidence="POTENTIAL",
                    endpoint=probe_url,
                    description=(
                        "Marker string reflected in response for parameters: "
                        + ", ".join(reflected)
                        + ". This is a non-destructive indicator that may require context-aware validation."
                    ),
                    remediation="Apply context-aware output encoding and strict input validation.",
                    cwe="CWE-79",
                    cvss_score=3.1,
                    verification="LIKELY",
                    verification_details="Benign marker string was reflected in server response.",
                    evidence=evidence,
                )
            )
        return findings
