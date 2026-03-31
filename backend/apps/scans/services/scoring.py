from collections import Counter

from .checks.helpers import severity_weight

SURFACE_CATEGORIES = {
    "reachability",
    "redirects",
    "tls",
    "headers",
    "email_security",
    "public_files",
    "certificate_transparency",
    "fingerprint",
    "performance",
    "surface_scan",
}



def _risk_level(score):
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"



def _should_skip_combined_deduction(item):
    category = (item.get("category") or "").lower()
    title = (item.get("title") or "").lower()
    description = (item.get("description") or "").lower()

    if category in SURFACE_CATEGORIES:
        return True
    if category == "github_repository" and ("could not be scanned" in title or "url is invalid" in title):
        return True
    if category == "auth_checks":
        return True
    if "rate limit exceeded" in description:
        return True
    return False



def calculate_security_score(findings):
    base_score = 100
    deduction = sum(severity_weight(item["severity"]) for item in findings)
    return max(0, min(100, base_score - deduction))



def calculate_combined_security_score(findings, base_score=100, existing_breakdown=None):
    score = base_score if base_score is not None else 100
    scoring_breakdown = list(existing_breakdown or [])

    for item in findings:
        if _should_skip_combined_deduction(item):
            continue
        points = severity_weight(item.get("severity"))
        if not points:
            continue
        score -= points
        scoring_breakdown.append(
            {
                "key": item.get("category"),
                "points": points,
                "title": item.get("title"),
                "reason": item.get("description"),
            }
        )

    score = max(0, min(100, score))
    return {
        "score": score,
        "risk_level": _risk_level(score),
        "scoring_breakdown": scoring_breakdown,
    }



def calculate_vibe_risk_score(findings):
    vibe_findings = [item for item in findings if item["category"] == "vibe_code"]
    score = 0
    for finding in vibe_findings:
        if finding["severity"] == "critical":
            score += 35
        elif finding["severity"] == "warning":
            score += 18
        else:
            score += 7
    return max(0, min(100, score))



def summarize_findings(findings):
    counts = Counter(item["severity"] for item in findings)
    categories = Counter(item["category"] for item in findings)
    return {
        "critical_count": counts.get("critical", 0),
        "warning_count": counts.get("warning", 0),
        "info_count": counts.get("info", 0),
        "top_categories": categories.most_common(8),
    }



def fallback_summary(project_name, findings):
    if not findings:
        return f"AEGIS AI did not detect actionable findings for {project_name} in this safe, non-destructive scan pass."

    summary = summarize_findings(findings)
    categories = ", ".join(category for category, _count in summary["top_categories"][:4]) or "general security hygiene"
    return f"AEGIS AI found {summary['critical_count']} critical issues, {summary['warning_count']} warnings, and {summary['info_count']} informational items for {project_name}. Most activity clustered around {categories}."
