import base64
import json
import re
from urllib.parse import urlparse

import requests
from django.conf import settings

from .helpers import build_finding

INTERESTING_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".env", ".txt", ".md", ".html"}
IGNORED_PATH_SEGMENTS = {
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "site-packages",
    "vendor",
    "dist",
    "build",
    ".next",
    "coverage",
    "target",
    "out",
    "__pycache__",
    ".git",
    ".idea",
    ".vscode",
}
IGNORED_FILE_SUFFIXES = {".min.js", ".map", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}
ROUTE_KEYWORDS = ("/api/", "/auth/", "/login", "/signin", "/token", "/session", "/admin")
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"), "critical", "Private key material committed"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "critical", "AWS access key pattern detected"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "critical", "Hardcoded secret-like value detected"),
]
RISKY_CODE_PATTERNS = [
    (re.compile(r"dangerouslySetInnerHTML"), "warning", "dangerouslySetInnerHTML usage"),
    (re.compile(r"\beval\s*\("), "warning", "eval usage"),
    (re.compile(r"verify\s*=\s*False"), "warning", "TLS verification disabled in code"),
    (re.compile(r"DEBUG\s*=\s*True"), "warning", "Debug mode enabled in source"),
    (re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]"), "warning", "Wildcard CORS policy in code"),
]
MALWARE_PATTERNS = [
    (re.compile(r"(?is)(powershell|cmd\.exe|bash)\b.{0,160}(invoke-webrequest|curl|wget).{0,200}(http|https)"), "critical", "Remote payload execution pattern", "Code appears to download and execute content from a remote source."),
    (re.compile(r"(?is)(base64\.b64decode|frombase64string|atob)\(.{0,240}(exec|eval|marshal|pickle|subprocess)"), "critical", "Obfuscated execution pattern", "Code appears to decode obfuscated content and execute it."),
    (re.compile(r"(?is)child_process\.(exec|spawn)\(.{0,220}(curl|wget|powershell|bash)"), "critical", "Command downloader pattern", "Code appears to spawn a process that downloads or executes remote content."),
    (re.compile(r"(?i)(xmrig|minerd|coinhive|stratum\+tcp)"), "critical", "Possible cryptominer indicator", "Code contains strings commonly associated with cryptomining malware."),
    (re.compile(r"(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot)"), "warning", "Possible exfiltration webhook", "Code contains webhook or bot endpoints that can be used for covert exfiltration."),
]
ROUTE_PATTERNS = [
    re.compile(r"(?:app|router)\.(get|post|put|patch|delete|options|head|use)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\b(fetch|axios\.(?:get|post|put|patch|delete))\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"\b(?:path|re_path)\(\s*r?['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"['\"]((?:/api/|/auth/|/login|/signin|/token|/session|/admin)[^'\"\s)]*)['\"]", re.IGNORECASE),
]


def _parse_repo(url):
    if not url:
        return None
    parsed = urlparse(url)
    if "github.com" not in parsed.netloc.lower():
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    return parts[0], parts[1].removesuffix(".git")


def _fetch_json(url, headers=None, timeout=8):
    response = requests.get(url, headers=headers or {}, timeout=timeout)
    response.raise_for_status()
    return response.json()


def _github_headers():
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "AEGIS-AI"}
    token = getattr(settings, "GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _should_skip_path(path):
    normalized = (path or "").strip("/").lower()
    if not normalized:
        return False
    segments = [segment for segment in normalized.split("/") if segment]
    if any(segment in IGNORED_PATH_SEGMENTS for segment in segments):
        return True
    return any(normalized.endswith(suffix) for suffix in IGNORED_FILE_SUFFIXES)


def _fetch_repo_files(owner, repo, branch, limit=60):
    headers = _github_headers()
    queue = [f"https://api.github.com/repos/{owner}/{repo}/contents?ref={branch}"]
    visited = set()
    files = []

    while queue and len(files) < limit:
        listing_url = queue.pop(0)
        if listing_url in visited:
            continue
        visited.add(listing_url)
        try:
            items = _fetch_json(listing_url, headers=headers)
        except Exception:
            continue
        if isinstance(items, dict):
            items = [items]
        for item in items:
            item_type = item.get("type")
            path = item.get("path", "")
            if _should_skip_path(path):
                continue
            if item_type == "dir" and path.count("/") <= 4:
                queue.append(item.get("url"))
                continue
            if item_type != "file" or len(files) >= limit:
                continue
            if not any(path.endswith(ext) for ext in INTERESTING_EXTENSIONS) or item.get("size", 0) > 50000:
                continue
            try:
                file_payload = _fetch_json(item.get("url"), headers=headers)
                content = base64.b64decode(file_payload.get("content", "")).decode("utf-8", errors="ignore")
                files.append({"path": path, "content": content[:16000]})
            except Exception:
                continue
    return files


def _normalize_route(route):
    normalized = (route or "").strip()
    if not normalized:
        return ""
    normalized = normalized.replace("^", "").replace("$", "")
    normalized = normalized.replace("<str:", "{").replace("<int:", "{").replace(">", "}")
    normalized = normalized.replace("(?P<", "{").replace(">[^/]+)", "}")
    normalized = normalized.replace("//", "/")
    if normalized.startswith("http://") or normalized.startswith("https://"):
        parsed = urlparse(normalized)
        normalized = parsed.path or "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized.lstrip('/')}"
    return normalized


def _route_looks_interesting(route):
    lowered = (route or "").lower()
    return any(keyword in lowered for keyword in ROUTE_KEYWORDS)


def _discover_routes(files, repo_label):
    routes = []
    seen = set()
    for item in files:
        content = item["content"]
        source = f"{repo_label}:{item['path']}"
        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                if len(match.groups()) == 2:
                    first, second = match.groups()
                    method = first.upper() if first and first.lower() in {"get", "post", "put", "patch", "delete", "options", "head", "use"} else "GET"
                    route = second
                else:
                    method = "GET"
                    route = match.group(1)
                route = _normalize_route(route)
                if not route or not _route_looks_interesting(route):
                    continue
                key = (repo_label, method, route)
                if key in seen:
                    continue
                seen.add(key)
                routes.append({"method": method, "route": route, "source": source, "repo_label": repo_label})
    return routes


def _dependency_findings(path, content, repo_label):
    findings = []
    display_path = f"{repo_label}:{path}"
    if path.lower().endswith("package.json"):
        try:
            payload = json.loads(content)
            deps = dict(payload.get("dependencies", {}))
            deps.update(payload.get("devDependencies", {}))
            for name, version in deps.items():
                if any(marker in str(version) for marker in ["*", "latest", "github:", "file:", "workspace:"]):
                    findings.append(build_finding("dependency_hygiene", "warning", "Unpinned JavaScript dependency", f"Dependency {name} uses a risky version expression: {version}", file_path=display_path, recommendation="Pin exact or narrowly-ranged dependency versions."))
        except Exception:
            pass
    if path.lower().endswith("requirements.txt"):
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "==" not in stripped and "git+" not in stripped:
                findings.append(build_finding("dependency_hygiene", "warning", "Python dependency not pinned exactly", f"Dependency entry {stripped} is not pinned to an exact version.", file_path=display_path, recommendation="Use exact versions for repeatable builds."))
    return findings

def _malware_findings(path, content, repo_label):
    findings = []
    display_path = f"{repo_label}:{path}"
    for pattern, severity, title, description in MALWARE_PATTERNS:
        if pattern.search(content):
            findings.append(
                build_finding(
                    "github_malware",
                    severity,
                    title,
                    f"{description} Review {display_path} carefully for malware or supply-chain abuse.",
                    file_path=display_path,
                    recommendation="Review the file manually, remove suspicious execution logic, and rotate any exposed secrets if compromise is possible.",
                )
            )
    return findings



def scan_github_repository(project):
    repository_targets = project.get_github_repositories()
    if not repository_targets:
        return {
            "findings": [],
            "metadata": {
                "repos": [],
                "repo_count": 0,
                "note": "No GitHub repository URL configured.",
                "discovered_routes": [],
                "discovered_route_count": 0,
                "scanned_file_count": 0,
                "scanned_files": [],
                "scanned_repo_count": 0,
                "failed_repo_count": 0,
                "overall_status": "not_available",
                "malware_issue_count": 0,
            },
            "code_samples": [],
        }

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "AEGIS-AI"}
    findings = []
    code_samples = []
    metadata = {
        "repos": [],
        "repo_count": len(repository_targets),
        "discovered_routes": [],
        "discovered_route_count": 0,
        "scanned_file_count": 0,
        "scanned_files": [],
        "scanned_repo_count": 0,
        "failed_repo_count": 0,
        "overall_status": "success",
        "malware_issue_count": 0,
    }

    for repo_label, repo_url in repository_targets:
        repo_parts = _parse_repo(repo_url)
        if not repo_parts:
            findings.append(build_finding("github_repository", "warning", "GitHub repository URL is invalid", f"The configured {repo_label} repository URL could not be parsed: {repo_url}", recommendation="Use a public GitHub repository URL like https://github.com/org/repo."))
            metadata["failed_repo_count"] += 1
            metadata["repos"].append({
                "label": repo_label,
                "url": repo_url,
                "status": "invalid",
                "discovered_routes": [],
                "discovered_route_count": 0,
                "scanned_file_count": 0,
                "scanned_files": [],
            })
            continue

        owner, repo = repo_parts
        repo_metadata = {"label": repo_label, "url": repo_url, "owner": owner, "repo": repo, "status": "success"}
        try:
            repo_meta = _fetch_json(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
            repo_metadata["default_branch"] = repo_meta.get("default_branch")
            repo_metadata["private"] = repo_meta.get("private")
            files = _fetch_repo_files(owner, repo, repo_metadata["default_branch"])
            repo_metadata["scanned_file_count"] = len(files)
            repo_metadata["scanned_files"] = [f"{repo_label}:{item['path']}" for item in files]
        except Exception as exc:
            findings.append(build_finding("github_repository", "warning", "GitHub repository could not be scanned", f"AEGIS AI could not inspect the configured {repo_label} repository: {exc}", recommendation="Ensure the repository URL is public, reachable, and not rate-limited."))
            repo_metadata["status"] = "check_failed"
            repo_metadata["error"] = str(exc)
            repo_metadata["discovered_routes"] = []
            repo_metadata["discovered_route_count"] = 0
            repo_metadata["scanned_file_count"] = repo_metadata.get("scanned_file_count", 0)
            repo_metadata["scanned_files"] = repo_metadata.get("scanned_files", [])
            metadata["failed_repo_count"] += 1
            metadata["repos"].append(repo_metadata)
            continue

        metadata["scanned_repo_count"] += 1
        repo_routes = _discover_routes(files, repo_label)
        repo_metadata["discovered_routes"] = repo_routes
        repo_metadata["discovered_route_count"] = len(repo_routes)
        metadata["repos"].append(repo_metadata)
        metadata["discovered_routes"].extend(repo_routes)
        metadata["scanned_files"].extend(repo_metadata["scanned_files"])
        metadata["scanned_file_count"] += repo_metadata["scanned_file_count"]

        for item in files:
            path = item["path"]
            display_path = f"{repo_label}:{path}"
            content = item["content"]
            code_samples.append({"path": display_path, "repo_label": repo_label, "content": content})
            for pattern, severity, title in SECRET_PATTERNS:
                if pattern.search(content):
                    findings.append(build_finding("github_secrets", severity, title, f"Potential secret material was detected in {display_path}.", file_path=display_path, recommendation="Rotate the secret and remove it from source control."))
            for pattern, severity, title in RISKY_CODE_PATTERNS:
                if pattern.search(content):
                    findings.append(build_finding("github_code", severity, title, f"Risky implementation pattern found in {display_path}.", file_path=display_path, recommendation="Replace the risky shortcut with a safer implementation."))
            findings.extend(_malware_findings(path, content, repo_label))
            findings.extend(_dependency_findings(path, content, repo_label))

    metadata["discovered_route_count"] = len(metadata["discovered_routes"])
    metadata["malware_issue_count"] = sum(1 for item in findings if item.get("category") == "github_malware")
    if metadata["failed_repo_count"] and not metadata["scanned_repo_count"]:
        metadata["overall_status"] = "check_failed"
    elif metadata["failed_repo_count"]:
        metadata["overall_status"] = "partial"
    elif metadata["scanned_repo_count"]:
        metadata["overall_status"] = "success"
    else:
        metadata["overall_status"] = "not_available"
    return {"findings": findings, "metadata": metadata, "code_samples": code_samples}
