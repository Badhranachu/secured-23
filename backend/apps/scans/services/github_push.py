import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from django.conf import settings

from apps.ai_core.services.ai_service import AIService

logger = logging.getLogger(__name__)


class GitHubPushError(RuntimeError):
    pass


class GitHubPushService:
    def __init__(self, scan_result, selected_vulnerabilities, commit_message=""):
        self.scan_result = scan_result
        self.project = scan_result.project
        self.selected_vulnerabilities = list(selected_vulnerabilities)
        self.commit_message = (commit_message or "").strip()
        self.logs = []

    def log(self, message):
        sanitized = self._sanitize_log_text(message)
        self.logs.append(sanitized)
        logger.info(sanitized)

    def execute(self):
        token = getattr(settings, "GITHUB_TOKEN", "")
        branch_override = (getattr(settings, "GITHUB_PUSH_BRANCH", "main") or "main").strip()
        if not token:
            raise GitHubPushError("GitHub push is not configured. Add GITHUB_TOKEN in backend/.env.")

        grouped = self._group_vulnerabilities_by_repo_and_file(branch_override=branch_override)
        if not grouped:
            raise GitHubPushError("No accepted code findings were supplied for a push.")

        self.log(f"[push] project={self.project.name} scan_id={self.scan_result.id} accepted_files={sum(len(payload['files']) for payload in grouped.values())}")
        commits = []
        changed_files = []
        skipped_files = []
        verification = []

        for repo_label, repo_payload in grouped.items():
            repo_url = repo_payload["repo_url"]
            default_branch = repo_payload["default_branch"]
            files = repo_payload["files"]
            owner, repo = self._parse_repo(repo_url)
            authed_url = self._authenticated_repo_url(repo_url, token)
            self.log(f"[push] repo_label={repo_label} repo_url={repo_url} branch={default_branch}")
            self.log(f"[push] token_included_in_remote_url={bool(token)} remote_url_masked={self._mask_authenticated_url(authed_url)}")

            with tempfile.TemporaryDirectory(prefix="aegis-gitpush-") as temp_dir:
                repo_dir = Path(temp_dir) / repo
                self.log(f"[push] local_repo_path={repo_dir}")
                if repo_dir.exists():
                    self.log(f"[push] deleting stale local repo path={repo_dir}")
                    self._delete_repo_dir(repo_dir)

                self._run_git(
                    ["git", "clone", "--depth", "1", "--branch", default_branch, authed_url, str(repo_dir)],
                    cwd=temp_dir,
                    step="clone",
                )
                self._run_git(["git", "remote", "set-url", "origin", authed_url], cwd=repo_dir, step="remote-set-url")
                self._run_git(["git", "remote", "-v"], cwd=repo_dir, capture_output=True, step="remote-v")

                updated_paths = []
                providers_used = set()
                for relative_path, vulnerabilities in files.items():
                    absolute_path = repo_dir / relative_path
                    display_path = f"{repo_label}:{relative_path}"
                    if not absolute_path.exists() or not absolute_path.is_file():
                        skipped_files.append({"path": display_path, "reason": "Repository file not found in cloned repo."})
                        self.log(f"[push] skipped={display_path} reason=repository file not found")
                        continue

                    original_content = absolute_path.read_text(encoding="utf-8")
                    self.log(f"[push] rewriting={display_path} findings={len(vulnerabilities)}")
                    rewrite = AIService().rewrite_code_for_security(
                        project_name=self.project.name,
                        file_path=display_path,
                        original_content=original_content,
                        findings=[
                            {
                                "title": item.title,
                                "description": item.description,
                                "recommendation": item.recommendation,
                            }
                            for item in vulnerabilities
                        ],
                    )
                    new_content = rewrite.get("content", "")
                    if not new_content or new_content == original_content:
                        skipped_files.append({"path": display_path, "reason": "No code change was generated for this file."})
                        self.log(f"[push] skipped={display_path} reason=no code change generated")
                        continue

                    providers_used.add(rewrite.get("provider") or "unknown")
                    absolute_path.write_text(new_content, encoding="utf-8")
                    updated_paths.append(relative_path)
                    changed_files.append(display_path)
                    self.log(f"[push] updated={display_path}")

                if not updated_paths:
                    self.log(f"[push] repo_label={repo_label} no committable files remained")
                    continue

                self._run_git(["git", "add", *updated_paths], cwd=repo_dir, step="add")
                pending_status = self._run_git(["git", "status", "--short"], cwd=repo_dir, capture_output=True, step="status").strip()
                if not pending_status:
                    self.log(f"[push] repo_label={repo_label} nothing to commit after add; treating as already up to date")
                    continue

                commit_message = self.commit_message or self._build_commit_message(repo_label, updated_paths)
                if not commit_message:
                    raise GitHubPushError("Commit message is required for push.")
                self.log(f"[push] commit_message={commit_message}")
                commit_output = self._run_git(["git", "commit", "-m", commit_message], cwd=repo_dir, capture_output=True, step="commit")
                commit_sha = self._run_git(["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, step="rev-parse").strip()
                push_error = None
                try:
                    self._run_git(["git", "push", "origin", default_branch], cwd=repo_dir, step="push")
                except GitHubPushError as exc:
                    push_error = exc
                    self.log(f"[push] push command reported error, verifying remote head before failing: {exc}")

                remote_sha = self._read_remote_head(repo_dir, default_branch)
                log_sha = self._run_git(["git", "log", "-1", "--format=%H"], cwd=repo_dir, capture_output=True, step="verify-local").strip()
                commit_url = f"https://github.com/{owner}/{repo}/commit/{commit_sha}"
                verification.append({"repo": f"{owner}/{repo}", "branch": default_branch, "local_head": log_sha, "remote_head": remote_sha})

                if push_error and remote_sha != commit_sha:
                    raise push_error

                if push_error and remote_sha == commit_sha:
                    self.log(f"[push] remote already contains commit={commit_sha}; treating prior push result as success")

                self.log(f"[push] Push successful")
                self.log(f"[push] Commit hash: {commit_sha}")
                self.log(f"[push] Files updated: {len(updated_paths)}")
                commits.append({
                    "repo_label": repo_label,
                    "repo": f"{owner}/{repo}",
                    "branch": default_branch,
                    "commit_message": commit_message,
                    "commit_sha": commit_sha,
                    "commit_url": commit_url,
                    "providers_used": sorted(providers_used),
                    "files": [f"{repo_label}:{path}" for path in updated_paths],
                    "commit_output": commit_output.strip(),
                })

        if commits:
            final_commit = commits[-1]["commit_sha"]
            self.log(f"[push] final_status=success commit_hash={final_commit} changed_files={len(changed_files)} skipped_files={len(skipped_files)}")
            return {
                "status": "success",
                "message": "Code pushed successfully" if not skipped_files else f"Code pushed successfully with {len(skipped_files)} skipped file(s).",
                "commit": final_commit,
                "logs": self.logs,
                "commits": commits,
                "changed_files": changed_files,
                "skipped_files": skipped_files,
                "verification": verification,
            }

        self.log("[push] final_status=success no new commits created; repository already up to date or no rewriteable changes")
        return {
            "status": "success",
            "message": "No new changes were necessary; repository appears up to date.",
            "commit": None,
            "logs": self.logs,
            "commits": commits,
            "changed_files": changed_files,
            "skipped_files": skipped_files,
            "verification": verification,
        }

    def _group_vulnerabilities_by_repo_and_file(self, branch_override="main"):
        repo_map = dict(self.project.get_github_repositories())
        branch_map = {
            item.get("label"): item.get("default_branch") or branch_override or "main"
            for item in (((self.scan_result.raw_json or {}).get("detailed_report") or {}).get("github", {}) or {}).get("repos", [])
        }
        grouped = {}
        for vulnerability in self.selected_vulnerabilities:
            repo_label, relative_path = self._split_file_path(vulnerability.file_path)
            repo_url = repo_map.get(repo_label)
            if not repo_url:
                raise GitHubPushError(f"No repository URL is configured for repo label: {repo_label}")
            grouped.setdefault(repo_label, {
                "repo_url": repo_url,
                "default_branch": branch_map.get(repo_label) or branch_override or "main",
                "files": {},
            })
            grouped[repo_label]["files"].setdefault(relative_path, []).append(vulnerability)
        return grouped

    def _split_file_path(self, value):
        if ":" not in (value or ""):
            raise GitHubPushError(f"Unsupported file path for GitHub push: {value}")
        repo_label, relative_path = value.split(":", 1)
        return repo_label.strip(), relative_path.strip().replace("\\", "/")

    def _parse_repo(self, url):
        parsed = urlparse(url)
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) < 2:
            raise GitHubPushError(f"Invalid GitHub repository URL: {url}")
        return parts[0], parts[1].removesuffix(".git")

    def _authenticated_repo_url(self, repo_url, token):
        parsed = urlparse(repo_url)
        return f"https://{token}@{parsed.netloc}{parsed.path}"

    def _mask_authenticated_url(self, url):
        parsed = urlparse(url)
        if "@" not in parsed.netloc:
            return url
        _, host = parsed.netloc.split("@", 1)
        return f"{parsed.scheme}://***@{host}{parsed.path}"

    def _sanitize_log_text(self, value):
        text = str(value)
        return re.sub(r"https://[^@\s]+@github\.com/[^\s]+", lambda match: self._mask_authenticated_url(match.group(0)), text)

    def _delete_repo_dir(self, repo_dir):
        for child in repo_dir.glob("**/*"):
            if child.is_file():
                child.unlink(missing_ok=True)
        for child in sorted(repo_dir.glob("**/*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        repo_dir.rmdir()

    def _read_remote_head(self, repo_dir, branch):
        remote_output = self._run_git(["git", "ls-remote", "origin", branch], cwd=repo_dir, capture_output=True, step="verify-remote").strip()
        if not remote_output:
            return ""
        parts = remote_output.split()
        return parts[0] if parts else ""

    def _build_commit_message(self, repo_label, updated_paths):
        if len(updated_paths) == 1:
            return f"fix(security): remediate {repo_label} {updated_paths[0]}"
        return f"fix(security): remediate {len(updated_paths)} {repo_label} files for {self.project.name}"

    def _run_git(self, command, cwd=None, capture_output=False, step="git"):
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        self.log(f"[git:{step}] command={self._sanitize_log_text(' '.join(command))} cwd={cwd}")
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        if stdout:
            self.log(f"[git:{step}] stdout={self._sanitize_log_text(stdout)}")
        if stderr:
            self.log(f"[git:{step}] stderr={self._sanitize_log_text(stderr)}")
        if completed.returncode != 0:
            raise GitHubPushError(f"{step} failed: {stderr or stdout or 'git command failed'}")
        return completed.stdout if capture_output else ""
