from urllib.parse import urlparse

CODE_RELATED_CATEGORIES = {
    "github_code",
    "github_secrets",
    "github_malware",
    "dependency_hygiene",
    "vibe_code",
    "auth_checks",
    "api_endpoints",
    "headers",
    "public_files",
}

HEADER_KEYWORDS = {
    "content-security-policy": ["middleware", "security", "header", "helmet", "next.config", "vercel.json", "server", "app.py", "main.py", "settings.py"],
    "strict-transport-security": ["middleware", "security", "header", "helmet", "next.config", "vercel.json", "server", "nginx", "app.py", "main.py", "settings.py"],
    "x-frame-options": ["middleware", "security", "header", "helmet", "next.config", "vercel.json", "server", "app.py", "main.py", "settings.py"],
    "x-content-type-options": ["middleware", "security", "header", "helmet", "next.config", "vercel.json", "server", "app.py", "main.py", "settings.py"],
    "referrer-policy": ["middleware", "security", "header", "helmet", "next.config", "vercel.json", "server", "app.py", "main.py", "settings.py"],
}

PUBLIC_FILE_CANDIDATES = {
    "security.txt": ["public/.well-known/security.txt", "static/.well-known/security.txt", ".well-known/security.txt", "src/app/.well-known/security.txt/route.ts", "app/.well-known/security.txt/route.ts"],
    "robots.txt": ["public/robots.txt", "static/robots.txt", "src/app/robots.ts", "app/robots.ts"],
}


def _safe_lower(value):
    return (value or "").lower()


def _normalize_path(path):
    return (path or "").replace("\\", "/").strip("/")


def _parse_endpoint_path(value):
    if not value:
        return ""
    parsed = urlparse(value)
    return parsed.path or (value if str(value).startswith("/") else "")


def _path_score(path, keywords):
    lowered = _safe_lower(path)
    return sum(1 for keyword in keywords if keyword in lowered)


def _build_repo_indexes(github_output, code_samples):
    repos = {item.get("label"): item for item in (github_output.get("metadata", {}).get("repos", []) or []) if item.get("label")}
    paths_by_repo = {label: [sample.get("path", "") for sample in code_samples if sample.get("repo_label") == label] for label in repos}
    route_sources = github_output.get("metadata", {}).get("discovered_routes", []) or []
    return repos, paths_by_repo, route_sources


def _best_route_match(endpoint_path, route_sources):
    target = _parse_endpoint_path(endpoint_path)
    if not target:
        return None
    best = None
    best_score = 0
    for route in route_sources:
        route_path = route.get("route") or ""
        source = route.get("source") or ""
        if not route_path or not source:
            continue
        score = 0
        if route_path == target:
            score = 100
        elif target.startswith(route_path.rstrip("/")) or route_path.startswith(target.rstrip("/")):
            score = 70
        elif route_path.strip("/") and route_path.strip("/") in target:
            score = 45
        if score > best_score:
            best_score = score
            best = source
    return best


def _best_path_candidate(paths, preferred_paths=None, keywords=None):
    normalized_paths = [_normalize_path(path.split(":", 1)[1] if ":" in path else path) for path in paths]
    original_map = {(_normalize_path(path.split(":", 1)[1] if ":" in path else path)): path for path in paths}

    best = None
    best_score = 0

    for preferred in preferred_paths or []:
        preferred_normalized = _normalize_path(preferred)
        if preferred_normalized in original_map:
            return original_map[preferred_normalized]

    for normalized in normalized_paths:
        score = 0
        if keywords:
            score += _path_score(normalized, keywords) * 10
        if normalized.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".txt")):
            score += 2
        if score > best_score:
            best_score = score
            best = original_map[normalized]
    return best if best_score > 0 else None


def _resolve_header_file(paths, finding):
    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("recommendation", ""),
    ]).lower()
    for header_name, keywords in HEADER_KEYWORDS.items():
        if header_name in text:
            return _best_path_candidate(paths, keywords=keywords)
    return _best_path_candidate(paths, keywords=["middleware", "security", "header", "helmet", "next.config", "vercel.json", "server", "settings.py"])


def _resolve_public_file(paths, finding):
    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("recommendation", ""),
    ]).lower()
    if "security.txt" in text:
        return _best_path_candidate(paths, preferred_paths=PUBLIC_FILE_CANDIDATES["security.txt"], keywords=["security.txt", ".well-known", "public", "static"])
    if "robots.txt" in text:
        return _best_path_candidate(paths, preferred_paths=PUBLIC_FILE_CANDIDATES["robots.txt"], keywords=["robots.txt", "public", "static"])
    return None


def _resolve_auth_or_api_file(paths, route_sources, finding):
    endpoint = finding.get("endpoint", "")
    route_match = _best_route_match(endpoint, route_sources)
    if route_match:
        return route_match

    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("recommendation", ""),
        endpoint,
    ]).lower()
    keywords = ["auth", "login", "signin", "token", "session", "admin", "user", "account", "profile", "api", "views", "controller", "route", "middleware"]
    if "cors" in text:
        keywords.extend(["cors", "middleware", "server", "settings.py", "next.config", "vercel.json"])
    if "cookie" in text or "httponly" in text or "csrf" in text:
        keywords.extend(["cookie", "session", "csrf", "auth", "middleware"])
    return _best_path_candidate(paths, keywords=keywords)


def _infer_repo_label(finding, repo_labels):
    explicit_path = finding.get("file_path") or ""
    if ":" in explicit_path:
        return explicit_path.split(":", 1)[0]

    endpoint = _safe_lower(finding.get("endpoint"))
    category = _safe_lower(finding.get("category"))
    labels = list(repo_labels)
    if not labels:
        return None
    if len(labels) == 1:
        return labels[0]

    if category in {"headers", "public_files"}:
        if "frontend" in labels:
            return "frontend"
    if category in {"auth_checks", "api_endpoints"}:
        if "backend" in labels:
            return "backend"
    if endpoint and any(token in endpoint for token in ["/api/", "/auth/", "/admin", "/login", "/token"]):
        if "backend" in labels:
            return "backend"
    return labels[0]


def resolve_finding_file_paths(findings, github_output, code_samples):
    repos, paths_by_repo, route_sources = _build_repo_indexes(github_output, code_samples)
    repo_labels = list(repos.keys())
    resolved = []

    for finding in findings:
        item = dict(finding)
        category = _safe_lower(item.get("category"))
        if item.get("file_path") or category not in CODE_RELATED_CATEGORIES:
            resolved.append(item)
            continue

        repo_label = _infer_repo_label(item, repo_labels)
        repo_paths = paths_by_repo.get(repo_label, [])
        matched = None

        if repo_paths:
            if category in {"auth_checks", "api_endpoints"}:
                repo_route_sources = [route for route in route_sources if route.get("repo_label") == repo_label]
                matched = _resolve_auth_or_api_file(repo_paths, repo_route_sources, item)
            elif category == "headers":
                matched = _resolve_header_file(repo_paths, item)
            elif category == "public_files":
                matched = _resolve_public_file(repo_paths, item)
            else:
                matched = _best_path_candidate(repo_paths, keywords=["security", "auth", "api", "config", "settings", "middleware", "route"])

        if matched and repo_label and ":" not in matched:
            matched = f"{repo_label}:{matched}"
        if matched:
            evidence = dict(item.get("evidence") or {})
            evidence["auto_file_mapping"] = True
            evidence["auto_file_mapping_reason"] = "heuristic_repo_issue_mapping"
            item["file_path"] = matched
            item["evidence"] = evidence
        resolved.append(item)

    return resolved
