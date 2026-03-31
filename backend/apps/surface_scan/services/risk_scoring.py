from collections import Counter

SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}



def _risk_level(score):
    if score >= 80:
        return "LOW"
    if score >= 60:
        return "MEDIUM"
    if score >= 40:
        return "HIGH"
    return "CRITICAL"



def _fallback_summary(hostname, score, risk_level, findings):
    if not findings:
        return f"{hostname} is reachable and this safe public scan did not flag major surface issues."
    return f"{hostname} scored {score}/100 and is currently rated {risk_level}. The most important issue was: {findings[0]['description']}"



def calculate_surface_risk(hostname, findings):
    score = 100
    scoring_breakdown = []
    recommendations = []
    seen_recommendations = set()

    for item in findings:
        points = int(item.get("deduction_points") or 0)
        if points:
            score -= points
            scoring_breakdown.append(
                {
                    "key": item.get("deduction_key") or item.get("key"),
                    "points": points,
                    "title": item.get("title"),
                    "reason": item.get("description"),
                }
            )
        recommendation = item.get("recommendation")
        if recommendation and recommendation not in seen_recommendations:
            seen_recommendations.add(recommendation)
            recommendations.append(recommendation)

    score = max(0, min(100, score))
    findings.sort(key=lambda item: (SEVERITY_RANK.get(item["severity"], 0), item.get("deduction_points", 0)), reverse=True)
    counts = Counter(item["severity"] for item in findings)
    risk_level = _risk_level(score)

    return {
        "score": score,
        "risk_level": risk_level,
        "summary": _fallback_summary(hostname, score, risk_level, findings),
        "findings": findings,
        "top_findings": findings[:3],
        "recommendations": recommendations,
        "top_recommendations": recommendations[:3],
        "scoring_breakdown": scoring_breakdown,
        "severity_counts": {
            "critical": counts.get("critical", 0),
            "warning": counts.get("warning", 0),
            "info": counts.get("info", 0),
        },
    }
