import socket

from .helpers import build_finding


def run_subdomain_check(project):
    findings = []
    resolved = []
    raw_subdomains = (project.subdomains or "").replace(",", "\n").splitlines()
    subdomains = [item.strip() for item in raw_subdomains if item.strip()]

    for subdomain in subdomains:
        try:
            addresses = sorted({info[4][0] for info in socket.getaddrinfo(subdomain, None)})
            resolved.append({"subdomain": subdomain, "addresses": addresses})
        except Exception:
            findings.append(
                build_finding(
                    "subdomains",
                    "warning",
                    "Subdomain did not resolve",
                    f"The configured subdomain {subdomain} could not be resolved from the scanner host.",
                    endpoint=subdomain,
                    recommendation="Verify DNS records and whether this subdomain should still be scanned.",
                )
            )

    return {"findings": findings, "metadata": {"resolved": resolved, "count": len(subdomains)}}
