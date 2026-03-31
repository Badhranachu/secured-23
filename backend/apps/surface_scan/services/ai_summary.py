import json

from apps.ai_core.providers.ollama import OllamaProvider
from apps.ai_core.providers.openrouter import OpenRouterProvider


class DomainAISummaryService:
    def _fallback_ai_copy(self, hostname, score_bundle, email_security_snapshot, redirect_snapshot, fingerprint_snapshot):
        issues = score_bundle.get("top_findings", [])[:3]
        recommendations = score_bundle.get("top_recommendations", [])[:3]
        issue_lines = "\n".join(f"- {item['title']}: {item['description']}" for item in issues) or "- No major public-surface issues were detected."
        recommendation_lines = "\n".join(f"- {item}" for item in recommendations) or "- Keep monitoring DNS, headers, redirects, and certificate validity."
        summary_bits = [f"{hostname} scored {score_bundle['score']}/100 and is rated {score_bundle['risk_level']}." ]
        if redirect_snapshot.get("https_enforced"):
            summary_bits.append("HTTPS appears to be enforced through the redirect path.")
        if email_security_snapshot.get("email_spoofing_risk"):
            summary_bits.append(f"Email spoofing risk is currently assessed as {email_security_snapshot['email_spoofing_risk']}.")
        if fingerprint_snapshot.get("hosting_clues"):
            summary_bits.append(f"Hosting clues suggest: {', '.join(fingerprint_snapshot['hosting_clues'][:3])}.")
        return (
            "Summary:\n"
            + " ".join(summary_bits)
            + "\n\nTop 3 issues:\n"
            + issue_lines
            + "\n\nTop 3 recommendations:\n"
            + recommendation_lines
        )

    def generate(self, hostname, dns_snapshot, http_snapshot, header_snapshot, tls_snapshot, ct_snapshot, public_files_snapshot, fingerprint_snapshot, email_security_snapshot, timing_snapshot, score_bundle):
        payload = {
            "domain": hostname,
            "score": score_bundle.get("score"),
            "risk_level": score_bundle.get("risk_level"),
            "top_findings": score_bundle.get("top_findings", []),
            "top_recommendations": score_bundle.get("top_recommendations", []),
            "dns": dns_snapshot,
            "redirects": http_snapshot.get("redirect_analysis", {}),
            "reachability": {
                "http": {"status_code": http_snapshot.get("http", {}).get("status_code"), "reachable": http_snapshot.get("http", {}).get("reachable")},
                "https": {"status_code": http_snapshot.get("https", {}).get("status_code"), "reachable": http_snapshot.get("https", {}).get("reachable")},
                "final_url": http_snapshot.get("final_url"),
            },
            "headers": header_snapshot,
            "tls": tls_snapshot,
            "certificate_transparency": ct_snapshot,
            "public_files": public_files_snapshot,
            "fingerprint": fingerprint_snapshot,
            "email_security": email_security_snapshot,
            "timing": timing_snapshot,
            "scoring_breakdown": score_bundle.get("scoring_breakdown", []),
        }

        messages = [
            {
                "role": "system",
                "content": (
                    "You explain safe web-security scan results in plain English for non-technical founders. "
                    "Keep the response concise and practical. Return exactly three sections titled Summary, Top 3 issues, and Top 3 recommendations. "
                    "Mention redirect problems, DNS/email security gaps, public file issues, and hosting clues only when they materially matter."
                ),
            },
            {"role": "user", "content": json.dumps(payload, indent=2, default=str)},
        ]

        providers = [OpenRouterProvider(), OllamaProvider()]
        errors = []
        for provider in providers:
            if not provider.is_available():
                continue
            try:
                return {"provider": provider.provider_name, "content": provider.generate_chat_completion(messages=messages)}
            except Exception as exc:
                errors.append(f"{provider.provider_name}: {exc}")

        return {
            "provider": "fallback",
            "content": self._fallback_ai_copy(hostname, score_bundle, email_security_snapshot, http_snapshot.get("redirect_analysis", {}), fingerprint_snapshot),
            "errors": errors,
        }
