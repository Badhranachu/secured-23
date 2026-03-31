import socket
import ssl
from datetime import datetime, timezone

from .helpers import build_finding, host_from_value, port_from_value



def run_ssl_tls_check(project):
    findings = []
    metadata = {}
    host = host_from_value(project.domain)
    port = port_from_value(project.domain, default_port=443)
    metadata["host"] = host
    metadata["port"] = port

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
                version = secure_sock.version()
                cipher = secure_sock.cipher()

        metadata["tls_version"] = version
        metadata["cipher"] = cipher[0] if cipher else None
        metadata["issuer"] = cert.get("issuer")
        metadata["subject"] = cert.get("subject")
        metadata["not_after"] = cert.get("notAfter")

        not_after = cert.get("notAfter")
        if not_after:
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expires_at - datetime.now(timezone.utc)).days
            metadata["days_remaining"] = days_remaining
            if days_remaining < 0:
                findings.append(
                    build_finding(
                        "ssl_tls",
                        "critical",
                        "TLS certificate expired",
                        "The target certificate is already expired.",
                        endpoint=f"{host}:{port}",
                        recommendation="Renew and redeploy the TLS certificate immediately.",
                        evidence={"days_remaining": days_remaining},
                    )
                )
            elif days_remaining <= 30:
                findings.append(
                    build_finding(
                        "ssl_tls",
                        "warning",
                        "TLS certificate expiring soon",
                        "The target certificate is close to expiry.",
                        endpoint=f"{host}:{port}",
                        recommendation="Rotate the certificate before it expires.",
                        evidence={"days_remaining": days_remaining},
                    )
                )

        if version in {"TLSv1", "TLSv1.1"}:
            findings.append(
                build_finding(
                    "ssl_tls",
                    "warning",
                    "Legacy TLS version negotiated",
                    f"The handshake negotiated {version}, which is considered weak.",
                    endpoint=f"{host}:{port}",
                    recommendation="Disable TLS 1.0/1.1 and enforce TLS 1.2 or newer.",
                )
            )
    except Exception as exc:
        findings.append(
            build_finding(
                "ssl_tls",
                "critical",
                "TLS handshake failed",
                f"AEGIS AI could not complete a safe TLS handshake: {exc}",
                endpoint=f"{host}:{port}",
                recommendation="Check certificate trust, hostname bindings, and whether the expected TLS port is open.",
            )
        )

    return {"findings": findings, "metadata": metadata}
