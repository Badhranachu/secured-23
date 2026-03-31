from apps.surface_scan.services.result_utils import clean_list, clean_text, status_payload


FINGERPRINT_RULES = [
    {"marker": "cloudflare", "label": "Cloudflare", "type": "cdn", "confidence": "high"},
    {"marker": "cf-ray", "label": "Cloudflare", "type": "waf", "confidence": "high"},
    {"marker": "vercel", "label": "Vercel", "type": "hosting", "confidence": "high"},
    {"marker": "x-vercel-id", "label": "Vercel", "type": "hosting", "confidence": "high"},
    {"marker": "netlify", "label": "Netlify", "type": "hosting", "confidence": "high"},
    {"marker": "x-nf-request-id", "label": "Netlify", "type": "hosting", "confidence": "high"},
    {"marker": "github pages", "label": "GitHub Pages", "type": "hosting", "confidence": "medium"},
    {"marker": "github.io", "label": "GitHub Pages", "type": "hosting", "confidence": "medium"},
    {"marker": "nginx", "label": "nginx", "type": "server", "confidence": "medium"},
    {"marker": "apache", "label": "Apache", "type": "server", "confidence": "medium"},
    {"marker": "akamai", "label": "Akamai", "type": "cdn", "confidence": "medium"},
    {"marker": "fastly", "label": "Fastly", "type": "cdn", "confidence": "medium"},
]


def _cloudflare_dns_hint(dns_snapshot):
    records = (dns_snapshot or {}).get("records", {}) or {}
    a_values = records.get("a", {}).get("values", []) or []
    aaaa_values = records.get("aaaa", {}).get("values", []) or []
    joined = " ".join(str(value) for value in [*a_values, *aaaa_values]).lower()
    return any(marker in joined for marker in ["104.21.", "172.67.", "2606:4700:"])


def detect_fingerprint(hostname, dns_snapshot, http_snapshot, public_files_snapshot):
    headers = http_snapshot.get("selected_headers", {}) or {}
    homepage = public_files_snapshot.get("homepage", {}) or {}
    haystacks = [
        clean_text(homepage.get("server_header", "")).lower(),
        clean_text(homepage.get("x_powered_by", "")).lower(),
        clean_text(headers.get("server", "")).lower(),
        clean_text(headers.get("x-powered-by", "")).lower(),
        clean_text(headers.get("via", "")).lower(),
        clean_text(headers.get("cf-ray", "")).lower(),
        clean_text(headers.get("x-vercel-id", "")).lower(),
        clean_text(headers.get("x-nf-request-id", "")).lower(),
        " ".join(item.lower() for item in dns_snapshot.get("analysis", {}).get("provider_clues", [])),
        " ".join(item.lower() for item in homepage.get("framework_hints", [])),
    ]
    combined = " | ".join([item for item in haystacks if item])

    hosting_clues = []
    cdn_detected = []
    waf_detected = []
    confidence = "low"

    for rule in FINGERPRINT_RULES:
        if rule["marker"] in combined and rule["label"] not in hosting_clues:
            hosting_clues.append(rule["label"])
            if rule["type"] == "cdn" and rule["label"] not in cdn_detected:
                cdn_detected.append(rule["label"])
            if rule["type"] == "waf" and rule["label"] not in waf_detected:
                waf_detected.append(rule["label"])
            if rule["confidence"] == "high":
                confidence = "high"
            elif confidence != "high":
                confidence = "medium"

    if _cloudflare_dns_hint(dns_snapshot):
        if "Cloudflare" not in hosting_clues:
            hosting_clues.append("Cloudflare")
        if "Cloudflare" not in cdn_detected:
            cdn_detected.append("Cloudflare")
        if confidence != "high":
            confidence = "high"

    if not cdn_detected and any(header in headers for header in ["via", "x-cache", "age"]):
        cdn_detected.append("Generic CDN or reverse proxy")
        hosting_clues.append("Generic CDN or reverse proxy")
        if confidence == "low":
            confidence = "medium"

    framework_hints = public_files_snapshot.get("homepage", {}).get("framework_hints", []) or []
    powered_by = clean_text(homepage.get("x_powered_by") or headers.get("x-powered-by")) or None
    server_header = clean_text(homepage.get("server_header") or headers.get("server")) or None
    status = "success" if combined or hosting_clues else "not_available"

    return status_payload(
        status,
        server_header=server_header,
        powered_by=powered_by,
        cdn_detected=clean_list(cdn_detected),
        waf_detected=clean_list(waf_detected),
        hosting_clues=clean_list(hosting_clues),
        framework_hints=framework_hints,
        fingerprint_confidence=confidence,
    )
