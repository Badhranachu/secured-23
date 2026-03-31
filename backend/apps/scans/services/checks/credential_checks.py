from apps.common.utils import evaluate_password_strength

from .helpers import build_finding


def _credential_related_values(project, password_type):
    return [
        project.name,
        project.domain,
        project.server_ip_address if password_type == "server_password" else project.test_email,
        project.notification_email,
    ]


def _finding_for_strength(password_type, strength):
    if not strength.get("present"):
        return None

    level = strength.get("level")
    if level not in {"weak", "fair"}:
        return None

    is_server = password_type == "server_password"
    severity = "critical" if is_server and level == "weak" else "warning"
    title = "Weak server password detected" if is_server else "Weak API test-account password detected"
    description = (
        "The configured server password is weak enough that brute-force or credential-stuffing attacks become more realistic."
        if is_server
        else "The configured API test-account password is weak and could be guessed or reused if this account reaches sensitive routes."
    )
    recommendation_parts = []
    if is_server:
        recommendation_parts.append("Move to a 14+ character unique passphrase and prefer SSH keys over password-based server access.")
    else:
        recommendation_parts.append("Use a unique 12+ character password for the API test account, especially if the account can reach private endpoints.")
    recommendation_parts.extend(strength.get("suggestions")[:3])

    return build_finding(
        "credential_security",
        severity,
        title,
        description,
        recommendation=" ".join(recommendation_parts),
        evidence={
            "strength_level": strength.get("level"),
            "strength_score": strength.get("score"),
            "max_score": strength.get("max_score"),
        },
    )


def evaluate_project_credentials(project):
    test_strength = evaluate_password_strength(project.get_test_password(), _credential_related_values(project, "test_password"))
    server_strength = evaluate_password_strength(project.get_server_password(), _credential_related_values(project, "server_password"))

    findings = []
    for password_type, strength in (("test_password", test_strength), ("server_password", server_strength)):
        finding = _finding_for_strength(password_type, strength)
        if finding:
            findings.append(finding)

    weakest_level = "success"
    if any(item.get("severity") == "critical" for item in findings):
        weakest_level = "critical"
    elif findings:
        weakest_level = "warning"
    elif test_strength.get("present") or server_strength.get("present"):
        weakest_level = "success"
    else:
        weakest_level = "not_available"

    metadata = {
        "status": weakest_level,
        "test_password": test_strength,
        "server_password": server_strength,
        "improvement_count": sum(len(item.get("suggestions", [])) for item in (test_strength, server_strength)),
    }
    return {"findings": findings, "metadata": metadata}
