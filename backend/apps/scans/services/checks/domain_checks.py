from .helpers import SECURITY_HEADER_RECOMMENDATIONS, build_finding, normalize_domain, safe_request


def run_domain_header_check(project):
    findings = []
    metadata = {"attempted_urls": []}

    for candidate in normalize_domain(project.domain):
        metadata["attempted_urls"].append(candidate)
        response, error = safe_request("GET", candidate, allow_redirects=True, allow_insecure_fallback=True)
        if response is None:
            continue

        metadata["final_url"] = response.url
        metadata["status_code"] = response.status_code
        metadata["headers"] = dict(response.headers)
        if error:
            findings.append(
                build_finding(
                    "domain_headers",
                    "warning",
                    "HTTPS validation issue detected",
                    error,
                    endpoint=response.url,
                    recommendation="Fix the certificate chain and hostname validation for the public domain.",
                )
            )

        for header, recommendation in SECURITY_HEADER_RECOMMENDATIONS.items():
            if header not in {key.lower(): value for key, value in response.headers.items()}:
                findings.append(
                    build_finding(
                        "domain_headers",
                        "warning",
                        f"Missing header: {header}",
                        f"The domain response did not include the {header} security header.",
                        endpoint=response.url,
                        recommendation=recommendation,
                    )
                )

        if response.headers.get("server"):
            findings.append(
                build_finding(
                    "domain_headers",
                    "info",
                    "Server banner exposed",
                    "The application exposes a Server header, which can leak stack details.",
                    endpoint=response.url,
                    recommendation="Consider minimizing origin server banner exposure at the reverse proxy layer.",
                    evidence={"server": response.headers.get("server")},
                )
            )
        return {"findings": findings, "metadata": metadata}

    findings.append(
        build_finding(
            "domain_headers",
            "critical",
            "Domain unreachable",
            "AEGIS AI could not reach the configured domain over HTTP or HTTPS within the safe timeout.",
            recommendation="Verify DNS, local firewall rules, and whether the target site is publicly reachable.",
            evidence=metadata,
        )
    )
    return {"findings": findings, "metadata": metadata}
