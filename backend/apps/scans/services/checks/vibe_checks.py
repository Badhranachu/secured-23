import re

from .helpers import build_finding

VIBE_PATTERNS = [
    (re.compile(r"TODO.+auth", re.IGNORECASE), "warning", "TODO left in auth-sensitive code"),
    (re.compile(r"password123|changeme|admin@example.com", re.IGNORECASE), "warning", "Default credential pattern in source"),
    (re.compile(r"except\s+Exception\s*:\s*pass"), "warning", "Silent exception swallowing"),
    (re.compile(r"csrf_exempt"), "warning", "CSRF exemption pattern"),
    (re.compile(r"localStorage\.setItem\(.+token", re.IGNORECASE), "info", "Token persisted in localStorage"),
]


def analyze_vibe_patterns(project, code_samples):
    findings = []
    scanned_paths = []

    for sample in code_samples[:20]:
        scanned_paths.append(sample["path"])
        content = sample.get("content", "")
        for pattern, severity, title in VIBE_PATTERNS:
            if pattern.search(content):
                findings.append(build_finding("vibe_code", severity, title, f"Heuristic vibe-code pattern detected in {sample['path']}.", file_path=sample["path"], recommendation="Review this section manually and replace risky shortcuts with explicit security checks."))

    if not project.stack_name:
        findings.append(build_finding("vibe_code", "info", "Project stack not documented", "The project does not declare a stack/framework name, which reduces scanner context quality.", recommendation="Record the project stack so future scans can apply more targeted checks."))

    return {"findings": findings, "metadata": {"scanned_paths": scanned_paths, "sample_count": len(scanned_paths)}}
